
package Paws::ResourceGroups::DeleteGroup;
  use Moose;
  has Group => (is => 'ro', isa => 'Str');
  has GroupName => (is => 'ro', isa => 'Str');

  use MooseX::ClassAttribute;

  class_has _api_call => (isa => 'Str', is => 'ro', default => 'DeleteGroup');
  class_has _api_uri  => (isa => 'Str', is => 'ro', default => '/delete-group');
  class_has _api_method  => (isa => 'Str', is => 'ro', default => 'POST');
  class_has _returns => (isa => 'Str', is => 'ro', default => 'Paws::ResourceGroups::DeleteGroupOutput');
1;

### main pod documentation begin ###

=head1 NAME

Paws::ResourceGroups::DeleteGroup - Arguments for method DeleteGroup on L<Paws::ResourceGroups>

=head1 DESCRIPTION

This class represents the parameters used for calling the method DeleteGroup on the
L<AWS Resource Groups|Paws::ResourceGroups> service. Use the attributes of this class
as arguments to method DeleteGroup.

You shouldn't make instances of this class. Each attribute should be used as a named argument in the call to DeleteGroup.

=head1 SYNOPSIS

    my $resource-groups = Paws->service('ResourceGroups');
    my $DeleteGroupOutput = $resource -groups->DeleteGroup(
      Group     => 'MyGroupString',    # OPTIONAL
      GroupName => 'MyGroupName',      # OPTIONAL
    );

    # Results:
    my $Group = $DeleteGroupOutput->Group;

    # Returns a L<Paws::ResourceGroups::DeleteGroupOutput> object.

Values for attributes that are native types (Int, String, Float, etc) can passed as-is (scalar values). Values for complex Types (objects) can be passed as a HashRef. The keys and values of the hashref will be used to instance the underlying object.
For the AWS API documentation, see L<https://docs.aws.amazon.com/goto/WebAPI/resource-groups/DeleteGroup>

=head1 ATTRIBUTES


=head2 Group => Str

The name or the ARN of the resource group to delete.



=head2 GroupName => Str

Deprecated - don't use this parameter. Use C<Group> instead.




=head1 SEE ALSO

This class forms part of L<Paws>, documenting arguments for method DeleteGroup in L<Paws::ResourceGroups>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

