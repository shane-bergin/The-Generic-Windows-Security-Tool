using System.Collections.Generic;
using System.Linq;

namespace TGWST.App.Shell
{
    /// <summary>
    /// Rich detail content for menu items, supporting multi-level expansion.
    /// </summary>
    public sealed class DetailContent
    {
        public string Summary { get; init; } = "";
        public string[] Changes { get; init; } = [];
        public string[] Risks { get; init; } = [];
        public string? RollbackInfo { get; init; }
        public string? Prerequisites { get; init; }
    }

    public sealed class MenuNode
    {
        public MenuNode(
            string title,
            string? command = null,
            string? description = null,
            string? detail = null,
            DetailContent? richDetail = null,
            IEnumerable<MenuNode>? children = null)
        {
            Title = title;
            Command = command;
            Description = description;
            Detail = detail;
            RichDetail = richDetail;
            Children = children?.ToList() ?? new List<MenuNode>();
            foreach (var child in Children)
            {
                child.Parent = this;
            }
        }

        public string Title { get; }
        public string? Command { get; }
        public string? Description { get; }
        public string? Detail { get; }
        public DetailContent? RichDetail { get; }
        public IReadOnlyList<MenuNode> Children { get; }
        public MenuNode? Parent { get; private set; }

        public bool HasChildren => Children.Count > 0;
    }
}
